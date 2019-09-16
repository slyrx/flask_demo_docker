# python:alpine is 3.{latest}
FROM python 

LABEL maintainer="Jeeva S. Chelladhurai"

RUN pip install flask
RUN pip install pycryptodome

COPY src /src/

EXPOSE 5000

CMD ["python", "/src/app.py"]
