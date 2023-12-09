# Real-time Intrusion Detection Web App
<b>Project III</b><br>
<b>Nguyễn Việt Hoàng - 20194434</b><br>
## About
* Real-time Intrusion Detection System implementing Machine Learning. 

* We combine Supervised learning (RF) for detecting known attacks from CICIDS 2018 & SCVIC-APT datasets, and Unsupervised Learning (AE) for anomaly detection.

* System descriptive diagram:
![image](https://github.com/HoangNV2001/Real-time-IDS/assets/72451372/78e0b74c-9db6-4bf5-8591-6d7aa8247b22)

## Requirements:
1. Windows OS.

2. Python 3.9:
    * link 64-bit: https://www.python.org/ftp/python/3.9.13/python-3.9.13-amd64.exe 
    * link 32-bit: https://www.python.org/ftp/python/3.9.13/python-3.9.13.exe

     <b> Note: select "Add Python 3.9 to PATH" in installation procedure.</b>

3. Npcap 1.71:
    https://npcap.com/dist/npcap-1.71.exe

## Download project folder & environment setups:
<code>git clone https://github.com/HoangNV2001/APT_Detection
    cd APT_Detection
    # Create a virtual environment
    python3.9 -m venv venv
    # Activate that virtual environment
    source venv/bin/activate
    # Install the project requirements.
    python -m pip install -r requirements.txt
    # or: pip install -r requirements.txt</code>

Run program:

<code>python application.py</code>

Web app address: [http://localhost:5000](http://localhost:5000)

## Demo GUI
* Main page, overview of real-time captured flows:

![image](https://github.com/HoangNV2001/Real-time-IDS/assets/72451372/90b42a1a-e2cb-4445-8036-4504e9c7c4ba)

* Flow detail page:

![image](https://github.com/HoangNV2001/Real-time-IDS/assets/72451372/c6ce1c6b-a006-461e-8872-d889abd69d0d)

