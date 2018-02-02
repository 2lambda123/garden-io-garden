const express = require("express")
const request = require("request-promise")

const app = express()

app.get("/hello", (req, res) => {
  // Query the example cloud function and return the response
  request.get(process.env.GARDEN_SERVICES_HELLO_FUNCTION_ENDPOINT)
    .then(response => {
      res.send(response)
    })
})

// This is the path GAE uses for health checks
app.get("/_ah/health", (req, res) => {
  res.sendStatus(200)
})

app.listen(process.env.PORT, "0.0.0.0", () => console.log("App started"))
