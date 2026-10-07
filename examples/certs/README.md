Put extra root CA certificates here (PEM format, file name ending in `.crt`),
for example your company's TLS-inspection proxy root CA. They are added to the
trust store of the build stage and the final collector image.

Files ending in `.crt` in this folder are git-ignored.
