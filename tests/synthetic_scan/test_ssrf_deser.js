const express = require('express');
const axios = require('axios');
const serialize = require('node-serialize');
const app = express();

app.use(express.json());

// SSRF Vulnerability
app.get('/unsafe-ssrf', async (req, res) => {
    // Taint source
    const targetUrl = req.query.url;
    
    // Taint sink
    try {
        const response = await axios.get(targetUrl);
        res.send(response.data);
    } catch (e) {
        res.status(500).send('Error');
    }
});

// Deserialization Vulnerability
app.post('/unsafe-deser', (req, res) => {
    // Taint source
    const payload = req.body.data;
    
    // Taint sink
    const obj = serialize.unserialize(payload);
    res.send('Deserialized');
});

app.listen(3000, () => {
    console.log('Server running');
});
