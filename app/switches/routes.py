from flask import render_template, request, redirect, url_for, flash, jsonify
from app import db
from app.models import Switch
from . import switches_bp
from .arista_utils import get_switch_data, push_switch_config, get_config_hash, get_arp_table

@switches_bp.route('/')
def index():
    switches = Switch.query.all()
    return render_template('index.html', switches=switches)

@switches_bp.route('/add', methods=['GET', 'POST'])
def add_switch():
    if request.method == 'POST':
        ip = request.form.get('ip_address')
        user = request.form.get('username')
        desc = request.form.get('description')
        
        new_switch = Switch(ip_address=ip, username=user, description=desc)
        db.session.add(new_switch)
        db.session.commit()
        return redirect(url_for('switches.index'))
        
    return render_template('add_switch.html')

@switches_bp.route('/manage/<int:id>', methods=['GET'])
def manage_switch(id):
    switch = Switch.query.get_or_404(id)
    data = get_switch_data(switch.ip_address, switch.username)
    return render_template('manage_switch.html', switch=switch, data=data)

@switches_bp.route('/manage/<int:id>/update', methods=['POST'])
def update_switch(id):
    switch = Switch.query.get_or_404(id)
    interface = request.form.get('interface')
    description = request.form.get('description')
    mode = request.form.get('mode')
    
    if mode == 'access':
        vlans = [request.form.get('access_vlan')]
    else:
        vlans = request.form.getlist('trunk_vlans')

    success = push_switch_config(switch.ip_address, switch.username, interface, description, mode, vlans)
    
    if success:
        flash(f"Successfully updated {interface} and saved to startup-config.", "success")
    else:
        flash(f"Failed to update {interface}.", "danger")
        
    return redirect(url_for('switches.manage_switch', id=switch.id))

@switches_bp.route('/api/hash/<int:id>')
def check_hash(id):
    switch = Switch.query.get_or_404(id)
    current_hash = get_config_hash(switch.ip_address, switch.username)
    return jsonify({'hash': current_hash})

@switches_bp.route('/manage/<int:id>/arp', methods=['GET'])
def arp_table(id):
    switch = Switch.query.get_or_404(id)
    arp_data = get_arp_table(switch.ip_address, switch.username)
    return render_template('arp_table.html', switch=switch, arp_data=arp_data)


