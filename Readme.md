# Active Firewall

## Requirements

* Tshark
  ```
  sudo apt install tshark
  sudo chmod +x /usr/bin/dumpcap
  ```
* Other Python packages:
    * pyshark

`pip install -r requirements.txt`

# Run application

Before running application please check `config.ini` file if configuration corresponds to your environment.

`sudo python3 main.py`

# Run tests

* Install pytest

  `pip install pytest`
* run tests

  `pytest`