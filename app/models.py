from app import *
from flask import Flask
from flask_sqlalchemy import SQLAlchemy


# from manage import api,db
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:walakokahibaw@localhost/db'
# app.config['SECRET_KEY'] = 'hard to guess string'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# db = SQLAlchemy(app)

# relationship between specifics and logs
activity = db.Table('activity',
                    db.Column('spec_num', db.Integer, db.ForeignKey('specifics.spec_num')),
                    db.Column('log_num', db.Integer, db.ForeignKey('logs.log_num'))
                    )
report = db.Table('report',
                    db.Column('item_num', db.Integer, db.ForeignKey('items.item_num')),
                    db.Column('prog_num', db.Integer, db.ForeignKey('progress.prog_num'))
                  )

class Account(db.Model):
    acc_id = db.Column(db.Integer, primary_key=True)
    acc_type = db.Column(db.Integer, unique=True)
    username = db.Column(db.String(60), unique=True)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(150), unique=True)
    acc_p = db.relationship("Parent", uselist=False, backref="account")
    acc_t = db.relation("Teacher", uselist=False, backref="account")

    def __init__(self, acc_type, username, email, password):
        self.acc_type = acc_type
        self.username = username
        self.email = email
        self.password = password

    def __repr__(self):
        return '<Account %r>' % self.acc_type

class Access_Token(db.Model):
    tkn_num = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(20), unique=True)

    def __init__(self, token):
        self.token = token

    def __repr__(self):
        return '<Access_Token %r>' % self.token

class Parent(db.Model):
    p_id = db.Column(db.Integer, primary_key=True)
    fname_p = db.Column(db.String(80))
    lname_p = db.Column(db.String(80))
    bday_p = db.Column(db.Date)
    add_p = db.Column(db.String(120))
    acc_id = db.Column(db.Integer, db.ForeignKey('account.acc_id'))
    child = db.relationship("Child", uselist=False, backref="parent")

    def __init__(self, fname_p, lname_p, bday_p, add_p):
        self.fname_p = fname_p
        self.lname_p = lname_p
        self.bday_p = bday_p
        self.add_p = add_p

    def __repr__(self):
        return '<Parent %r>' % self.fname_p
class Child(db.Model):
    c_id = db.Column(db.Integer, primary_key=True)
    fname_c = db.Column(db.String(80))
    lname_c = db.Column(db.String(80))
    bday_c = db.Column(db.Date)
    diagnosis = db.Column(db.String(50))
    p_id = db.Column(db.Integer, db.ForeignKey('parent.p_id'))
    pers = db.relationship('Personal', backref='child', lazy='dynamic')

    def __init__(self, fname_c, lname_c, bday_c, diagnosis):
        self.fname_c = fname_c
        self.lname_c = lname_c
        self.bday_c = bday_c
        self.diagnosis = diagnosis

    def __repr__(self):
        return '<Child %r>' % self.fname_c

class Teacher(db.Model):
    t_id = db.Column(db.Integer, primary_key=True)
    fname_t = db.Column(db.String(80))
    lname_t = db.Column(db.String(80))
    bday_t = db.Column(db.Date)
    specialty = db.Column(db.String(120))
    tel_num = db.Column(db.BigInteger)
    add_t = db.Column(db.String(120))
    acc_id = db.Column(db.Integer, db.ForeignKey('account.acc_id'))

    def __init__(self, fname_t, lname_t, bday_t, specialty, tel_num, add_t):
        self.fname_t = fname_t
        self.lname_t = lname_t
        self.bday_t = bday_t
        self.specialty = specialty
        self.tel_num = tel_num
        self.add_t = add_t

    def __repr__(self):
        return '<Teacher %r>' % self.fname_t

class Personal(db.Model):
    per_num = db.Column(db.Integer, primary_key=True)
    per_name = db.Column(db.String(50))
    child_id = db.Column(db.Integer, db.ForeignKey('child.c_id'))
    spec = db.relationship('Specifics', backref='specify', lazy='dynamic')

    def __init__(self, per_name):
        self.per_name = per_name

    def __repr__(self):
        return '<Personal %r>' % self.per_name

class Specifics(db.Model):
    spec_num = db.Column(db.Integer, primary_key=True)
    spec_name = db.Column(db.String(50))
    act = db.relationship('Logs', secondary=activity, backref=db.backref('act', lazy='dynamic'))
    specify_id = db.Column(db.Integer, db.ForeignKey('personal.per_num'))

    def __init__(self, spec_name):
        self.spec_name = spec_name

    def __repr__(self):
        return '<Specifics %r>' % self.spec_name

class Logs(db.Model):
    log_num = db.Column(db.Integer, primary_key=True)
    clicks = db.Column(db.Integer)
    log_date = db.Column(db.Date)
    log_time = db.Column(db.Time)

    def __init__(self, clicks, log_date, log_time):
        self.clicks = clicks
        self.log_date = log_date
        self.log_time = log_time

    def __repr__(self):
        return '<Logs %r>' % self.clicks

class Class(db.Model):
    class_num = db.Column(db.Integer, primary_key=True)
    class_name = db.Column(db.String(50))
    ed = db.relationship('Educational', backref='edu', lazy='dynamic')

    def __init__(self, class_name):
        self.class_name = class_name

    def __repr__(self):
        return '<Class %r>' % self.class_name

class Educational(db.Model):
    ed_num = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(50))
    edu_id = db.Column(db.Integer, db.ForeignKey('class.class_num'))

    def __init__(self, subject):
        self.subject = subject

    def __repr__(self):
        return '<Educational %r>' % self.per_subject

class Items(db.Model):
    item_num = db.Column(db.Integer, primary_key=True)
    desc = db.Column(db.String(120)),
    rep = db.relationship('Progress', secondary=report, backref=db.backref('rep', lazy='dynamic'))

    def __init__(self, desc):
        self.desc = desc

    def __repr__(self):
        return '<Items %r>' % self.desc

class Progress(db.Model):
    prog_num = db.Column(db.Integer, primary_key=True)
    details = db.Column(db.String(500))
    prog_date = db.Column(db.Date)
    prog_time = db.Column(db.Time)
    score = db.Column(db.Integer)

    def __init__(self, details, prog_date, prog_time, score):
        self.details = details
        self.prog_date = prog_date
        self.prog_time = prog_time
        self.score = score

    def __repr__(self):
        return '<Progress %r>' % self.details

class Images(db.Model):
    img_id = db.Column(db.Integer, primary_key=True)
    img = db.Column(db.String(50))

    def __init__(self, img):
        self.img = img

    def __repr__(self):
        return '<Images %r>' % self.img
class Audio(db.Model):
    aud_id = db.Column(db.Integer, primary_key=True)
    aud = db.Column(db.String(50))

    def __init__(self, aud):
        self.aud = aud

    def __repr__(self):
        return '<Audio %r>' % self.aud

# db.create_all()

if __name__ == '__main__':
    app.run()
