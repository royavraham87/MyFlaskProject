@app.route('/', methods=['GET',"POST"])
@app.route('/pub', methods=['GET',"POST"])
@app.route('/secret', methods=['GET',"POST"])
@app.route('/uploads/<filename>')