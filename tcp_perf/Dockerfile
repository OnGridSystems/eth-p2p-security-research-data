# Use the official Ubuntu base image
FROM ubuntu:latest

# Update the package list and install prerequisites
RUN apt-get update && apt-get install -y \
    software-properties-common \
    iputils-ping \
    softflowd \
    tcpdump \
    iproute2 \
    iptables \
    curl \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update

# Install Python 3.13
RUN apt-get install -y python3.13

# Set Python 3.13 as the default python3
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.13 1

# Verify the installation
RUN python3 --version

# Set the working directory
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY ./entrypoint.py /app

ENV PYTHONUNBUFFERED=1
# Run a command to keep the container running
CMD ["python3", "entrypoint.py"]
