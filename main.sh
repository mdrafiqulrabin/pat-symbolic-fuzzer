clear

echo; echo "Installing requirements..."; echo

python3 -m pip install -r requirements.txt

rm -rf outputs
mkdir outputs

python3 run_simple_symfz.py &> outputs/output.txt

echo
cat outputs/output.txt
echo
