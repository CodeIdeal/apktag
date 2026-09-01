# Keep the base APK read-only and emit independent channel packages

Batch packaging treats the base APK as immutable input and writes one independently named channel package per channel. This makes retries and partial failure safe and keeps the batch API deterministic.

## Considered Options

- Mutate the base APK in place for each channel.
- Share one mutable output while iterating channels.
- Write independent artifacts from an immutable base input.

## Consequences

Callers can reuse the same base APK for multiple batches, and a failed channel write cannot corrupt the source or another generated artifact. The default artifact name is `<channel>-<base>.apk`.
