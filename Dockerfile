# RENTAN (Lab L3.3): base image besar, berjalan sebagai root, menyalin seluruh repo,
# dan menjalankan server pengembangan Flask (debugger sudah dimatikan di L2.3).
FROM python:3.11
WORKDIR /app
COPY . /app
RUN pip install -r api/requirements.txt
# app.py default hanya mendengar 127.0.0.1; di container harus semua interface agar port bisa dipetakan.
ENV KOPIKITA_HOST=0.0.0.0
EXPOSE 5000
CMD ["python", "api/app.py"]
