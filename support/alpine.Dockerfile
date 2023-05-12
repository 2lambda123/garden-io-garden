#
# garden-base
#
FROM node:18-alpine3.17 as garden-alpine-base

RUN apk add --no-cache \
  bash \
  curl \
  docker-cli \
  git \
  openssl \
  rsync \
  ca-certificates \
  tar \
  gzip \
  openssh-client \
  libstdc++ \
  python3 \
  py3-pip \
  libc6-compat \
  py3-openssl \
  libffi \
  gnupg \
  openssh-client \
  py3-crcmod

# Note: This is run with the dist/alpine-amd64 directory as the context root
ADD . /garden
WORKDIR /project

RUN chmod +x /garden/garden \
  && ln -s /garden/garden /usr/local/bin/garden \
  && chmod +x /usr/local/bin/garden \
  && cd /garden/static \
  && GARDEN_DISABLE_ANALYTICS=true GARDEN_DISABLE_VERSION_CHECK=true garden util fetch-tools --all --garden-image-build

ENTRYPOINT ["/garden/garden"]

FROM python:3.8-alpine AS aws-builder

ENV AWSCLI_VERSION=2.11.18

RUN apk add --no-cache \
  curl \
  make \
  cmake \
  gcc \
  g++ \
  libc-dev \
  libffi-dev \
  openssl-dev
RUN curl https://awscli.amazonaws.com/awscli-$AWSCLI_VERSION.tar.gz | tar -xz
RUN cd awscli-$AWSCLI_VERSION \
  && ./configure --bindir=/usr/local/bin --prefix=/aws-cli/ --with-download-deps --with-install-type=portable-exe \
  && make \
  && make install

#
# garden-aws-base
#
FROM garden-alpine-base as garden-aws-base

COPY --from=aws-builder /aws-cli /aws-cli

RUN curl -o aws-iam-authenticator https://amazon-eks.s3.us-west-2.amazonaws.com/1.15.10/2020-02-22/bin/linux/amd64/aws-iam-authenticator \
  && chmod +x ./aws-iam-authenticator \
  && mv ./aws-iam-authenticator /usr/bin/

#
# gcloud base
#
FROM google/cloud-sdk:430.0.0-alpine as gcloud-base

RUN gcloud components install kubectl gke-gcloud-auth-plugin --quiet

# Clean up bloat that increases layer size unnecessarily
RUN rm -rf $(find /google-cloud-sdk/ -regex ".*/__pycache__") && rm -rf /google-cloud-sdk/.install/.backup

#
# garden-azure-base
#
FROM garden-alpine-base as garden-azure-base

WORKDIR /
ENV AZURE_CLI_VERSION=2.48.1

RUN wget -O requirements.txt https://raw.githubusercontent.com/Azure/azure-cli/azure-cli-$AZURE_CLI_VERSION/src/azure-cli/requirements.py3.Linux.txt
RUN wget -O trim_sdk.py https://raw.githubusercontent.com/Azure/azure-cli/azure-cli-$AZURE_CLI_VERSION/scripts/trim_sdk.py

RUN apk add py3-virtualenv openssl-dev libffi-dev build-base python3-dev
RUN python3 -m virtualenv /azure-cli
ENV PATH /azure-cli/bin:$PATH

RUN pip install -r requirements.txt && python trim_sdk.py

#
# garden-azure
#
FROM garden-alpine-base as garden-azure

COPY --from=garden-azure-base /azure-cli /azure-cli
RUN ln -s /azure-cli/bin/az /usr/local/bin/az

RUN az aks install-cli

# Required by Azure DevOps to tell the system where node is installed
LABEL "com.azure.dev.pipelines.agent.handler.node.path"="/usr/local/bin/node"

#
# garden-aws
#
FROM garden-alpine-base as garden-aws

RUN apk --no-cache add groff

# Copy aws cli
COPY --from=garden-aws-base /aws-cli/lib/aws-cli /aws-cli
# Copy aws-iam-authenticator from aws
COPY --from=garden-aws-base /usr/bin/aws-iam-authenticator /usr/bin
ENV PATH /aws-cli:$PATH


#
# garden-gloud
#
FROM garden-alpine-base as garden-gcloud

ENV CLOUDSDK_PYTHON=python3

COPY --from=gcloud-base /google-cloud-sdk /google-cloud-sdk
ENV PATH /google-cloud-sdk/bin:$PATH

#
# garden-aws-gloud
#
FROM garden-alpine-base as garden-aws-gcloud

RUN apk --no-cache add groff

# Copy aws cli
COPY --from=garden-aws-base /aws-cli/lib/aws-cli /aws-cli
# Copy aws-iam-authenticator from aws
COPY --from=garden-aws-base /usr/bin/aws-iam-authenticator /usr/bin
ENV PATH /aws-cli:$PATH

ENV CLOUDSDK_PYTHON=python3

COPY --from=gcloud-base /google-cloud-sdk /google-cloud-sdk
ENV PATH /google-cloud-sdk/bin:$PATH


#
# garden-aws-gloud-azure
#
FROM garden-alpine-base as garden-aws-gcloud-azure

RUN apk --no-cache add groff

# Copy aws cli
COPY --from=garden-aws-base /aws-cli/lib/aws-cli /aws-cli
# Copy aws-iam-authenticator from aws
COPY --from=garden-aws-base /usr/bin/aws-iam-authenticator /usr/bin
ENV PATH /aws-cli:$PATH

ENV CLOUDSDK_PYTHON=python3

COPY --from=gcloud-base /google-cloud-sdk /google-cloud-sdk
ENV PATH /google-cloud-sdk/bin:$PATH

COPY --from=garden-azure-base /azure-cli /azure-cli
RUN ln -s /azure-cli/bin/az /usr/local/bin/az

RUN az aks install-cli

# Required by Azure DevOps to tell the system where node is installed
LABEL "com.azure.dev.pipelines.agent.handler.node.path"="/usr/local/bin/node"
