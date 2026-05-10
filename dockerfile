FROM python:3.11-alpine
WORKDIR /app

COPY . .

RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

EXPOSE 8085
CMD [ "streamlit","run","app.py","--server.port","8085" ]