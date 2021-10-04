#Todo App with Login/Register using Python,Flask, and SQLite

---
##Sample Account to login with:
Username: TheBestUser1

Password: password1234

---


##REFERENCES/LINKS:

[SQLITE]
https://www.youtube.com/watch?v=jTiyt6W1Qpo&ab_channel=PrettyPrinted

[LOGIN/REGISTER]
https://github.com/PrettyPrinted/building_user_login_system/blob/master/finish/app.py

https://github.com/scoringengine/scoringengine/issues/670

Building todo web app from scratch https://www.youtube.com/watch?v=Z1RJmh_OqeA&ab_channel=NDCConferences

https://www.youtube.com/watch?v=hbDRTZarMUw&ab_channel=Codemy.com

https://www.youtube.com/watch?v=juPQ04_twtA&ab_channel=PrettyPrinted

https://www.google.com/search?q=how+to+delete+column+in+flask+databse&oq=how+to+delete+column+in+flask+databse&aqs=chrome..69i57j33i10i160l4.6538j1j7&sourceid=chrome&ie=UTF-8#kpvalbx=_t7FwYJj7J_DD_Qb-sInoCw12

https://www.youtube.com/watch?v=dam0GPOAvVI&ab_channel=TechWithTim

https://www.youtube.com/watch?v=Gjf0PxhGU0U&t=19s&ab_channel=ASATechnical

https://www.youtube.com/watch?v=Li0Abz-KT78&ab_channel=Codemy.com


##Errors and Tricks

No timer error with flask_sqlalchemy: just change if 

sys.platform == 'win64': and add config app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
__version__ = '0.14.2'

ImportError: cannot import name 'url_encode' from 'werkzeug'

---
#Instructions:

###flask db init (creates the database migration folder)

###flask db migrate -m "users table" (makes a migration based on your table changes)

###"snake case" = AddressAndPhone model class becomes address_and_phone

###Procfile  = File containing setting for the editor

###ctrl + shift + R = restet the css

###set FLASK_ENV=development
