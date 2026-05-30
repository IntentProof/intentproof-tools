# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder-go

RUN apt-get update && apt-get install -y git zip

ENV TOOLS_REF=19ccaeb9bf61c2c8fc9eaeeb4dc5a8e5e7ea51ab
ENV SPEC_REF=660526e20f9bd7d0912570620b49826e2b834781
ENV CORE_REF=b0a7a6f6b1bff674948d34251e70026556e06af0

RUN git clone https://github.com/IntentProof/intentproof-tools.git "$SRC/intentproof-tools" && \
    cd "$SRC/intentproof-tools" && git checkout "$TOOLS_REF"

RUN git clone https://github.com/IntentProof/intentproof-spec.git "$SRC/intentproof-spec" && \
    cd "$SRC/intentproof-spec" && git checkout "$SPEC_REF"

RUN git clone https://github.com/IntentProof/intentproof-core.git "$SRC/intentproof-core" && \
    cd "$SRC/intentproof-core" && git checkout "$CORE_REF"

WORKDIR $SRC/intentproof-tools
COPY build.sh $SRC/
