from includes.constants import FUZZER_APP_PKG_NAME, INVOKER_SERVICE, SYSTEM_UI_PKG_NAME

import itertools


class ParametersGenerator:

    INT_VALUES = ["INT:0", "INT:10", "INT:1", "INT:-1", "INT:0x7fffffff", "INT:UID:{}".format(FUZZER_APP_PKG_NAME),
                  "INT:UID:SECOND_PROFILE:{}".format(FUZZER_APP_PKG_NAME), "INT:UID:{}".format(SYSTEM_UI_PKG_NAME)]

    BOOLEAN_VALUES = ["B:true", "B:false"]

    STRING_VALUES = ["S:{}".format(FUZZER_APP_PKG_NAME), "S:{}".format(SYSTEM_UI_PKG_NAME)]

    COMPONENT_NAME_VALUES = [
        "COMPONENT_NAME:{}:{}.{}".format(FUZZER_APP_PKG_NAME, FUZZER_APP_PKG_NAME, INVOKER_SERVICE),
        "COMPONENT_NAME:com.meraki.sm:com.meraki.sm.DeviceAdmin"
    ]

    INTENT_VALUES = [
        "INTENT:{}:{}.{}".format(FUZZER_APP_PKG_NAME, FUZZER_APP_PKG_NAME, INVOKER_SERVICE),
        "INTENT:com.meraki.sm:com.meraki.sm.DeviceAdmin"
    ]

    URI_VALUES = [
        "URI:content://user_dictionary/words",
        "URI:content://com.android.contacts/contacts/lookup/0"
    ]

    def count_parameters_sets(self, parameters):
        if len(parameters) == 0:
            return 0

        int_values = self.INTENT_VALUES
        boolean_values = self.BOOLEAN_VALUES
        string_values = self.STRING_VALUES

        count = 1
        for parameter in parameters:
            if parameter == 'I':
                count = count * len(int_values)
            elif parameter == 'Z':
                count = count * len(boolean_values)
            elif parameter == 'java.lang.String':
                count = count * len(string_values)

        return count

    def generate_primitive_types(self, parameters):
        result = []

        if len(parameters) == 0:
            return result

        int_values = self.INTENT_VALUES
        boolean_values = self.BOOLEAN_VALUES
        string_values = self.STRING_VALUES

        keep_minimal = self.count_parameters_sets(parameters) > 20

        lists = []
        i_index = -1
        z_index = -1
        s_index = -1
        component_index = -1
        intent_index = -1
        uri_index = -1
        index = 0
        for parameter in parameters:
            if parameter == 'I':
                if keep_minimal:
                    if i_index == -1:
                        lists.append(int_values)
                        i_index = index
                    else:
                        lists.append(['INDEX:{}'.format(i_index)])
                else:
                    lists.append(int_values)
            elif parameter == 'Z':
                if keep_minimal:
                    if z_index == -1:
                        lists.append(boolean_values)
                        z_index = index
                    else:
                        lists.append(['INDEX:{}'.format(z_index)])
                else:
                    lists.append(boolean_values)
            elif parameter == 'java.lang.String':
                if keep_minimal:
                    if s_index == -1:
                        lists.append(string_values)
                        s_index = index
                    else:
                        lists.append(['INDEX:{}'.format(s_index)])
                else:
                    lists.append(string_values)
            elif parameter == 'android.content.ComponentName':
                if keep_minimal:
                    if component_index == -1:
                        lists.append(self.COMPONENT_NAME_VALUES)
                        component_index = index
                    else:
                        lists.append(['INDEX:{}'.format(component_index)])
                else:
                    lists.append(self.COMPONENT_NAME_VALUES)
            elif parameter == 'android.content.Intent':
                if keep_minimal:
                    if intent_index == -1:
                        lists.append(self.INTENT_VALUES)
                        intent_index = index
                    else:
                        lists.append(['INDEX:{}'.format(intent_index)])
                else:
                    lists.append(self.INTENT_VALUES)
            elif parameter == 'android.net.Uri':
                if keep_minimal:
                    if uri_index == -1:
                        lists.append(self.URI_VALUES)
                        uri_index = index
                    else:
                        lists.append(['INDEX:{}'.format(uri_index)])
                else:
                    lists.append(self.URI_VALUES)
            elif parameter != '':
                lists.append(["OBJ:{}".format(parameter)])

            index = index + 1

        return self.crunsh_parameters(lists)

    def crunsh_parameters(self, lists):
        result = []
        parameters_list = ['']
        for lst in lists:
            parameters_list = list(itertools.product(parameters_list, lst))

        for lst in parameters_list:
            while len(lst) > 0 and type(lst[0]) == tuple:
                lst = list(lst[0]) + list(lst[1:])
            result.append(lst[1:])

        if len(result) == 1 and result[0] == '':
            result = []

        return result

    def __init__(self):
        pass
