FROM python3.8-slim 

WORKDIR /app

COPY  requirements.txt .

RUN "pip install -r requirements.txt"

COPY .  .

CMD [ "pyton3", "manage.py" , "runserver", "8000" ]
