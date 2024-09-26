const express = require('express');
const path = require('path');

const app = express();

app.use(express.static('Webpages'));


app.get('/images/:imageName', (req, res) => {
  const imageName = req.params.imageName;
  res.sendFile(__dirname + '/images/' + imageName);
});
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'Monitoring system', 'Webpages', 'register.html'));
});
app.listen(3000, () => {
  console.log('Server started on port 3000');
});