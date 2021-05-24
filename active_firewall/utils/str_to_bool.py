def str_to_bool(v):
    """
    Converts string value into bool.

    :param v: representation of bool - 'True' or 'False'
    :type v: str
    :return: v converted into bool
    :rtype: str
    """
    return v.lower() in ("yes", "true", "t", "1")
