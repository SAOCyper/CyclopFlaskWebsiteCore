from website import create_app
app = create_app()
host='0.0.0.0'
port=8080


if __name__ == '__main__':
    app.run(host=host,port=port,debug=True)
