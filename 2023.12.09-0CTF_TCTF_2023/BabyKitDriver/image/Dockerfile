FROM crazymax/osxcross:13.1-ubuntu AS osxcross
FROM ubuntu:22.04
COPY --from=osxcross /osxcross /osxcross
RUN apt-get update && apt-get install -y clang lld libc6-dev
ENV PATH="/osxcross/bin:$PATH"
ENV LD_LIBRARY_PATH="/osxcross/lib:$LD_LIBRARY_PATH"
