import requests
from pwrpy.models.Delegator import Delegator


class Validator:
    def __init__(self, address, ip, bad_actor, voting_power, shares, delegators_count, status):
        self._address = address
        self._ip = ip
        self._bad_actor = bad_actor
        self._voting_power = voting_power
        self._shares = shares
        self._delegators_count = delegators_count
        self._delegators = []
        self._status = status

    @classmethod
    def from_json(cls, json_data):
        address = json_data.get("address", None)
        ip = json_data.get("ip", None)
        bad_actor = json_data.get("isBadActor", False)
        voting_power = json_data.get("votingPower", 0)
        shares = json_data.get("shares", 0)
        delegators_count = json_data.get("delegatorsCount", 0)
        status = json_data.get("status", None)
        return cls(address, ip, bad_actor, voting_power, shares, delegators_count, status)

    @property
    def address(self):
        return self._address

    @property
    def ip(self):
        return self._ip

    @property
    def bad_actor(self):
        return self._bad_actor

    @property
    def voting_power(self):
        return self._voting_power

    @property
    def shares(self):
        return self._shares

    @property
    def delegators_count(self):
        return self._delegators_count

    @property
    def status(self):
        return self._status

    def get_delegators(self, rpc_node_url):
        try:
            response = requests.get(
                rpc_node_url + "/validator/delegatorsOfValidator/?validatorAddress=" + self._address)

            # Check if the response was successful
            if response.status_code == 200:
                data = response.json()

                delegators_data = data['delegators']
                delegators_list = []

                for delegator_address, shares in delegators_data.items():
                    delegated_pwr = (shares * self._voting_power)
                    delegator = Delegator(
                        "0x" + delegator_address, self._address, shares, delegated_pwr)
                    delegators_list.append(delegator)

                return delegators_list
            elif response.status_code == 400:
                # If the response was a client error, raise an exception
                data = response.json()
                raise RuntimeError(f"Failed with HTTP error 400 and message: {data['message']}")
            else:
                # If the response was another kind of error, raise an exception
                raise RuntimeError(f"Failed with HTTP error code: {response.status_code}")

        except requests.HTTPError as http_err:
            raise RuntimeError(f"HTTP error occurred: {http_err}")
        except Exception as err:
            raise RuntimeError(f"An error occurred: {err}")
