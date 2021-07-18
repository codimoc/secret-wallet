FROM python:3.8-slim
WORKDIR /app
RUN pip install secret-wallet-codimoc
COPY secret_wallet.py /app
ENTRYPOINT ["python3","secret_wallet.py"]
CMD ["help"]