import express from 'express';
import vm from 'vm'

const app = express();
app.use(express.json());

const FLAG = "flag{REDACTED}";

app.post('/eval', (req, res) => {
    const { code } = req.body;
  
    if (typeof code !== 'string') {
      return res.status(400).send('Invalid code');
    }

    const allowedChars = new Set('+*-![]()'.split(''));
    for (const char of code) {
      if (!allowedChars.has(char)) {
        return res.status(400).send('Disallowed characters in code');
      }
    }

    if (/flag|FLAG|global|require|constructor|Function/.test(code)) {
      return res.status(400).send('Disallowed code');
    }

    const context = { flag: FLAG };
    vm.createContext(context);
  
    try {
      const result = vm.runInContext(code, context, { timeout: 1000 });
      res.send(String(result));
    } catch (err) {
      res
        .status(500)
        .send(`Error during execution: ${err.message}\n${err.stack}`);
    }
  });
  

app.listen(3000, () => console.log('Listening on port 3000'));

