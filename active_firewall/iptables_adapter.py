import atexit
import subprocess
from threading import Timer


class IptablesAdapter:

    def __init__(self, chain):
        self.chain = chain
        atexit.register(self.__flush_chain, self.chain)

    def add_rule_with_timeout(self, rule, timeout):
        if self.add_rule(rule):
            t = Timer(timeout, self.delete_rule, [rule])
            t.start()

    def add_rule(self, rule):
        add_rule = [self.chain, "-j", "DROP"] + rule
        if not IptablesAdapter.__check_if_rule_exists(add_rule):
            subprocess.call(["sudo", "iptables", "-A"] + add_rule)
            return True
        return False

    def add_custom_rule(self, rule):
        add_rule = [self.chain] + rule
        if not IptablesAdapter.__check_if_rule_exists(add_rule):
            subprocess.call(["sudo", "iptables", "-A"] + add_rule)
            return True
        return False

    def delete_rule(self, rule):
        delete_rule = [self.chain, "-j", "DROP"] + rule
        subprocess.call(["sudo", "iptables", "-D"] + delete_rule)

    @staticmethod
    def __check_if_rule_exists(rule):
        exist_response = subprocess.call(["sudo", "iptables", "-C"] + rule, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
        if exist_response == 0:
            print('rule exists')
        return exist_response == 0

    @staticmethod
    def __flush_chain(chain):
        # Uncomment if you want clear whole iptables chain on app exit
        print(f'Flushing {chain} rules')
        subprocess.call(["sudo", "iptables", "-F", chain])
        pass
