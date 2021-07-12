FROM registry.redhat.io/rhel8/python-38

ADD agent ./agent

COPY app.py  requirements.txt  .

RUN pip install -r requirements.txt

ENTRYPOINT ["python","app.py"]
