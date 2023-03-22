from qkay import app

if __name__ == "__main__":
  app.jinja_env.auto_reload = True
  app.config["TEMPLATES_AUTO_RELOAD"] = True
  app.run(host="0.0.0.0")