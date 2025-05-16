import express from 'express';
import vm from 'vm'

const app = express();
app.use(express.json());

const FLAG = "flag{REDACTED}";

app.post('/eval', (req, res) => {
    const { code } = req.body;
    console.log('Received code:', code);
  
    if (typeof code !== 'string') {
      return res.status(400).send('Invalid code');
    }

    if (/flag|FLAG|global|require|constructor|Function/.test(code)) {
      console.log('Rejected by filter.');
      return res.status(400).send('Disallowed code');
    }

    const context = { flag: FLAG };
    vm.createContext(context);
  
    try {
      const result = vm.runInContext(code, context, { timeout: 1000 });
      console.log('Execution result:', result);
      res.send(String(result));
    } catch (err) {
      console.error('VM error:', err);
      res
        .status(500)
        .send(`Error during execution: ${err.message}\n${err.stack}`);
    }
  });
  

app.listen(3000, () => console.log('Listening on port 3000'));

