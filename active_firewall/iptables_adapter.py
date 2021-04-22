import subprocess


class IptablesAdapter:
    @staticmethod
    def add_rule(rule):
        add = ["sudo", "iptables", "-A"]
        new_rules = add + rule
        subprocess.call(new_rules)

    @staticmethod
    def delete_rule(rule):
        delete = ["sudo", "iptables", "-D"]
        new_rules = delete + rule
        subprocess.call(new_rules)
