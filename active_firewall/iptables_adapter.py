import atexit
import subprocess
from threading import Timer


class IptablesAdapter:
    """
    Adapter class that can apply rules on ip tables tool.
    """

    def __init__(self, chain, clear_on_exit=False):
        """
        Constructor method

        :param chain: the name of the iptables chain to apply the rules to
        :type chain: str
        :param clear_on_exit: if flag raised, chain will be flushed after application exit
        :type clear_on_exit: bool, optional
        """
        self.applied_rules_timers = dict()
        self.chain = chain
        self.clear_on_exit = clear_on_exit
        atexit.register(self.__flush_chain, self.chain, self.clear_on_exit)

    def add_rule_with_timeout(self, rule, timeout):
        """
        Add a rule to iptables. After a defined time, it will be automatically deleted.
        If a rule is already applied, new timer will replace old one.

        :param rule: list of string defining rule that is applied into iptables
        :type rule: list
        :param timeout: time after which the rule will be revoked
        :type timeout: int
        """
        rule_id = ''.join(rule)

        if self.add_rule(rule):
            t = Timer(timeout, self.delete_rule, [rule])
            self.applied_rules_timers[rule_id] = t
            t.start()
        else:
            if rule_id in self.applied_rules_timers:
                old_t = self.applied_rules_timers[rule_id]
                old_t.cancel()
                t = Timer(timeout, self.delete_rule, [rule])
                self.applied_rules_timers[rule_id] = t
                t.start()

    def add_rule(self, rule):
        """
        Add a rule to iptables.

        :param rule: list of string defining rule that is applied into iptables
        :type rule: list
        """
        add_rule = [self.chain, "-j", "DROP"] + rule
        if not IptablesAdapter.__check_if_rule_exists(add_rule):
            subprocess.call(["sudo", "iptables", "-A"] + add_rule)
            return True
        return False

    def add_custom_rule(self, rule):
        """
        Add a rule to iptables. No additional flag will be added.

        :param rule: list of string defining rule that is applied into iptables
        :type rule: list
        """
        add_rule = [self.chain] + rule
        if not IptablesAdapter.__check_if_rule_exists(add_rule):
            subprocess.call(["sudo", "iptables", "-A"] + add_rule)
            return True
        return False

    def delete_rule(self, rule):
        """
        Removes a rule from iptables. Deletes timer if exist.

        :param rule: list of string defining rule that is removed from iptables
        :type rule: list
        """
        rule_id = ''.join(rule)
        if rule_id in self.applied_rules_timers:
            del self.applied_rules_timers[rule_id]

        delete_rule = [self.chain, "-j", "DROP"] + rule
        subprocess.call(["sudo", "iptables", "-D"] + delete_rule)

    @staticmethod
    def __check_if_rule_exists(rule):
        """
        Check if rule is already applied to iptables.

        :param rule: list of string defining rule that is removed from iptables
        :type rule: list
        :return if rule is already applied
        :rtype: bool
        """
        exist_response = subprocess.call(["sudo", "iptables", "-C"] + rule, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
        return exist_response == 0

    @staticmethod
    def __flush_chain(chain, clear_on_exit):
        """
        If clear_on_exit was raised it will flush iptables chain.

        :param clear_on_exit: flag defining if chain will be flushed
        :type clear_on_exit: bool
        """
        if clear_on_exit:
            print(f'Flushing {chain} rules')
            subprocess.call(["sudo", "iptables", "-F", chain])
