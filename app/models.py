import datetime

from app import db


class Switch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))


class SwitchNote(db.Model):
    """Local notes for a switch (application database only)."""

    id = db.Column(db.Integer, primary_key=True)
    switch_id = db.Column(db.Integer, db.ForeignKey("switch.id"), nullable=False, index=True)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

    switch = db.relationship("Switch", backref=db.backref("switch_notes", lazy="dynamic"))


class VlanNote(db.Model):
    """Local notes for a VLAN on a specific switch (application database only)."""

    id = db.Column(db.Integer, primary_key=True)
    switch_id = db.Column(db.Integer, db.ForeignKey("switch.id"), nullable=False, index=True)
    vlan_id = db.Column(db.Integer, nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

    switch = db.relationship("Switch", backref=db.backref("vlan_notes", lazy="dynamic"))
