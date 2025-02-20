//! This module and the `ResponseStream` type exist to safely parse and
//! handle the newline-delimited JSON streams returned by the LND REST
//! API's subscription endpoints, such as
//! [`/v1/channels/subscribe`](https://lightning.engineering/api-docs/api/lnd/lightning/subscribe-channel-events/).

use crate::errors::{BodyReadError, LndErrorResponse, RequestError, RequestErrorCause};
use http_body_util::BodyExt;
use hyper::body::Buf as _;
use serde::de::DeserializeOwned;
use utf8_read::Reader as Utf8Reader;

const MAX_RESPONSE_SIZE: usize = 100 * 1024 * 1024;

struct ResponseStreamInner<B> {
    buf: Vec<u8>,
    incoming: B,
}

enum DrainResult {
    Drained(Vec<u8>),
    NoNewline(usize),
}

/// LND wraps all event objects from subscription streams in a `{ "result": <data> }`
/// wrapper object. This doesn't seem to be documented in
/// [the official API reference](https://lightning.engineering/api-docs/api/lnd/).
#[derive(serde::Serialize, serde::Deserialize)]
struct StreamEvent<T> {
    #[serde(default = "default_option")]
    result: Option<T>,
    #[serde(default = "default_option")]
    error: Option<LndErrorResponse>,
}

fn default_option<T>() -> Option<T> {
    None
}

fn try_drain_newline_delim(
    buf: &mut Vec<u8>,
    search_pos: usize,
) -> Result<DrainResult, BodyReadError> {
    let mut chars = Utf8Reader::<&[u8]>::new(&buf[search_pos..]);

    while let Some(read_result) = (&mut chars).next() {
        match read_result {
            Ok(c) => {
                if c == '\n' {
                    let pos = *chars.borrow_pos();
                    let mut leading: Vec<u8> = buf.drain(..(search_pos + pos.byte())).collect();
                    leading.truncate(leading.len() - 1); // drop the trailing '\n' char
                    return Ok(DrainResult::Drained(leading));
                }
            }

            Err(e) => match e {
                utf8_read::Error::IoError(_) => unreachable!("Read never fails on &[u8]"),
                utf8_read::Error::MalformedUtf8(pos, trailing_invalid_bytes) => {
                    if search_pos + pos.byte() + trailing_invalid_bytes == buf.len() {
                        return Ok(DrainResult::NoNewline(trailing_invalid_bytes));
                    }
                    return Err(BodyReadError::InvalidUtf8);
                }
            },
        }
    }

    // Ran out of chars to read, didn't hit any newlines.
    Ok(DrainResult::NoNewline(0))
}

impl<B> ResponseStreamInner<B>
where
    B: BodyExt<Error = hyper::Error> + Unpin,
{
    fn new(incoming: B) -> Self {
        ResponseStreamInner {
            buf: Vec::with_capacity(4096),
            incoming,
        }
    }

    async fn next<O: DeserializeOwned>(&mut self) -> Result<Option<O>, BodyReadError> {
        // Tracks the number of trailing bytes of invalid UTF8, to keep track of
        // any UTF8 sequences that were broken up across multiple HTTP data frames.
        let mut trailing_invalid_bytes;

        match try_drain_newline_delim(&mut self.buf, 0)? {
            DrainResult::Drained(front) => {
                let StreamEvent { result, error } = serde_json::from_slice(&front)?;
                if let Some(err) = error {
                    return Err(BodyReadError::ErrorEvent(err));
                }
                return Ok(result);
            }
            DrainResult::NoNewline(invalid_bytes) => {
                trailing_invalid_bytes = invalid_bytes;
            }
        }

        while let Some(frame) = self.incoming.frame().await {
            match frame {
                Err(e) => return Err(BodyReadError::HttpFailure(e)),
                Ok(frame) => {
                    let Some(chunk) = frame.data_ref() else {
                        continue; // disregard non-data frames
                    };

                    // Safety: Prevent memory exhaustion
                    if self.buf.len() + chunk.remaining() > MAX_RESPONSE_SIZE {
                        return Err(BodyReadError::TooLarge);
                    }

                    let search_pos = self.buf.len() - trailing_invalid_bytes;
                    self.buf.extend(chunk.chunk());

                    // parse response objects delimited by newlines
                    match try_drain_newline_delim(&mut self.buf, search_pos)? {
                        DrainResult::Drained(front) => {
                            let StreamEvent { result, error } = serde_json::from_slice(&front)?;
                            if let Some(err) = error {
                                return Err(BodyReadError::ErrorEvent(err));
                            }
                            return Ok(result);
                        }
                        DrainResult::NoNewline(invalid_bytes) => {
                            trailing_invalid_bytes = invalid_bytes;
                        }
                    }
                }
            }
        }

        // Read no data, EOF
        if self.buf.is_empty() {
            return Ok(None);
        }

        // We're fresh out of data frames in the response, but we didn't encounter any newlines.
        // This must be a single-object response followed by EOF as occurs with some error responses.
        let StreamEvent { result, error } = serde_json::from_slice(&self.buf)?;

        // don't parse and return the same data object again.
        self.buf.truncate(0);

        if let Some(err) = error {
            return Err(BodyReadError::ErrorEvent(err));
        }
        return Ok(result);
    }
}

pub struct ResponseStream {
    endpoint: String,
    method: hyper::Method,
    stream: ResponseStreamInner<hyper::body::Incoming>,
}

impl ResponseStream {
    pub fn new(method: hyper::Method, endpoint: String, incoming: hyper::body::Incoming) -> Self {
        ResponseStream {
            method,
            endpoint,
            stream: ResponseStreamInner::new(incoming),
        }
    }

    pub async fn next<O: DeserializeOwned>(&mut self) -> Result<Option<O>, RequestError> {
        self.stream.next().await.map_err(|e| RequestError {
            endpoint: self.endpoint.clone(),
            method: self.method.clone(),
            cause: RequestErrorCause::BodyReadFailure(e),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body::Frame;
    use rand::Rng as _;
    use std::{
        collections::VecDeque,
        pin::Pin,
        task::{Context, Poll},
    };

    impl<T: serde::Serialize> StreamEvent<T> {
        fn result(result: T) -> Self {
            StreamEvent {
                result: Some(result),
                error: None,
            }
        }

        fn result_json(result: T) -> String {
            serde_json::to_string(&Self::result(result)).unwrap()
        }
    }

    const EMOJI_SMILE: char = '😊';
    const EMOJI_BYTES: [u8; 4] = [0xF0, 0x9F, 0x98, 0x8A];

    #[test]
    fn emoji_smile_bytes_check() {
        let mut emoji_bytes = [0u8; 4];
        EMOJI_SMILE.encode_utf8(&mut emoji_bytes);
        assert_eq!(emoji_bytes, EMOJI_BYTES);
    }

    struct MockBody {
        frames: VecDeque<VecDeque<u8>>,
    }

    impl MockBody {
        fn new<T: AsRef<[u8]>>(frames: &[T]) -> Self {
            MockBody {
                frames: VecDeque::from_iter(
                    frames
                        .into_iter()
                        .map(|f| VecDeque::from_iter(f.as_ref().into_iter().copied())),
                ),
            }
        }
    }

    impl hyper::body::Body for MockBody {
        type Data = VecDeque<u8>;
        type Error = hyper::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            let opt = self.frames.pop_front().map(|data| Ok(Frame::data(data)));
            Poll::Ready(opt)
        }
    }

    #[tokio::test]
    async fn response_stream_detects_newlines() {
        let mut stream = ResponseStreamInner::new(MockBody::new(&[
            "{\"result\":24}\n",
            "{\"result\": \"hi there\"}\n",
            "{\"result\": 72}\n",
        ]));
        assert_eq!(stream.next::<u32>().await.unwrap(), Some(24));
        assert_eq!(
            stream.next::<String>().await.unwrap(),
            Some(String::from("hi there"))
        );
        assert_eq!(stream.next::<u32>().await.unwrap(), Some(72));

        // Stream now empty
        assert!(matches!(stream.next::<u32>().await, Ok(None)));
        assert!(matches!(stream.next::<u32>().await, Ok(None)));
    }

    #[tokio::test]
    async fn response_stream_handles_utf8_across_http_frame_boundaries() {
        let emoji_string = format!("{}{}", EMOJI_SMILE, EMOJI_SMILE);
        let emoji_json_string = format!("{}\n", StreamEvent::result_json(emoji_string.clone()),);
        let emoji_string_bytes = emoji_json_string.as_bytes();
        let body = MockBody::new(&[
            &emoji_string_bytes[..8],
            &emoji_string_bytes[8..12],
            &emoji_string_bytes[12..],
        ]);

        let mut stream = ResponseStreamInner::new(body);

        assert_eq!(stream.next::<String>().await.unwrap(), Some(emoji_string));
        assert!(matches!(stream.next::<String>().await, Ok(None)));
    }

    #[tokio::test]
    async fn response_stream_handles_utf8_and_newlines() {
        let emoji_string = format!("{}{}", EMOJI_SMILE, EMOJI_SMILE);
        let emoji_event_json = StreamEvent::result_json(&emoji_string.clone());

        let emoji_json_strings_delimited = format!(
            "{}\n{}\n{}\n",
            emoji_event_json, emoji_event_json, emoji_event_json
        );
        let emoji_json_strings_bytes = emoji_json_strings_delimited.as_bytes();

        let mut rng = rand::thread_rng();

        // Randomly check various possible chunkings of the message
        for _ in 0..500 {
            let split_indexes: Vec<usize> = (1..(emoji_json_strings_bytes.len() - 1))
                .filter(|_| rng.gen::<f64>() > 0.9)
                .collect();

            let mut frames = Vec::new();
            let mut last_index = 0;
            for i in split_indexes {
                frames.push(&emoji_json_strings_bytes[last_index..i]);
                last_index = i;
            }
            frames.push(&emoji_json_strings_bytes[last_index..]);

            let mut stream = ResponseStreamInner::new(MockBody::new(&frames));

            assert_eq!(
                stream.next::<String>().await.unwrap(),
                Some(emoji_string.clone())
            );
            assert_eq!(
                stream.next::<String>().await.unwrap(),
                Some(emoji_string.clone())
            );
            assert_eq!(
                stream.next::<String>().await.unwrap(),
                Some(emoji_string.clone())
            );
            assert!(matches!(stream.next::<String>().await, Ok(None)));
        }
    }

    #[tokio::test]
    async fn response_stream_handles_newlines_inside_strings() {
        let mut json_string = StreamEvent::result_json("hello\nthere".to_string());
        json_string.push('\n');

        let mut stream =
            ResponseStreamInner::new(MockBody::new(&["{\"result\": 24}\n", &json_string]));

        assert_eq!(stream.next::<u32>().await.unwrap(), Some(24));
        assert_eq!(
            stream.next::<String>().await.unwrap(),
            Some(String::from("hello\nthere"))
        );

        // Stream now empty
        assert!(matches!(stream.next::<u32>().await, Ok(None)));
        assert!(matches!(stream.next::<u32>().await, Ok(None)));
    }
}
