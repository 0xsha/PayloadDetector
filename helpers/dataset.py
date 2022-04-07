import random
from itertools import chain
import pandas as pd
from helpers.ioutils import SimpleFile


class DataSetProcessor:

    # def __init__(self):
    #     pass

    @staticmethod
    def CreateBalancedDataSet():
        data_set = pd.read_csv("data/final/final.csv")

        final_samples = {"payload": [], "category": []}
        categories = ["xss", "xxe", "injection", "rce", "crlf", "deserialize", "lfi-ldf", "openredirect", "clean"]

        # data_set = pd.DataFrame()
        for index, row in data_set.iterrows():
            if row["category"] in categories:
                # print(row['category'])
                if KeyExist(row["category"], final_samples):

                    if CountKeys(row["category"], final_samples) <= 400:
                        final_samples["payload"].append(row["payload"])
                        final_samples["category"].append(row["category"])
                    else:
                        continue
                else:
                    if CountKeys(row["category"], final_samples) <= 400:
                        final_samples["payload"].append(row["payload"])
                        final_samples["category"].append(row["category"])

        interesting_clean_keywords = ["xss", "crlf", "xxe", "sqli", "injection", "lfi", "passwd", "etc", "onmouseover",
                                      "onload", "192.168.1.100:9887", "127.0.0.1", "10.255.255.255", "host", "localhost"
                                                                                                             "10.0.0.0",
                                      "172.31.255.255", "192.168.255.255", "192.168.0.0", "172.16.0.0", "wait", "count",
                                      "select", "google", "google.com", "www.google.com", "alert", "alert(1)"
                                                                                                   "bin", "bash",
                                      "curl", "where", "char", "exec", "cgi", "extractvalue", "1", "2", "3"
                                                                                                        "tftp",
                                      "192.168", "192.", "127.", "'", "<>",
                                      "<a>example.com</a>", "cmd", "<>@!@#$%^&*()_+", "<b>example.com<<>>@",
                                      "Mozilla/5.0 (X11; OpenBSD i386) AppleWebKit/537.36 (KHTML, like Gecko) "
                                      "Chrome/36.0.1985.125 Safari/537.36"]

        for item in interesting_clean_keywords:
            final_samples["payload"].append(item)
            final_samples["category"].append("clean")
        # print(len(final_samples["payload"]))
        final_samples = pd.DataFrame.from_dict(final_samples).sample(frac=1, random_state=555)
        final_samples.to_csv("data/final/final_sampled.csv", index=False)
        print("Final sample created in data directory as well")

    @staticmethod
    def ProcessDataSets():
        rce = []  # unix , windows, powershell, SSTI
        injection = []  # ldap, sql , nosql
        xss = []  # variants
        xxe = []  # variants
        lfi_lfd = []  # also sensitive files
        open_redirect = []
        crlf = []
        deserialize = []
        clean = []

        # # some entities from OWASP coreruleset

        SimpleFile.AppendFileToList(lfi_lfd, "data/sources/coreruleset/lfi.txt")
        SimpleFile.AppendFileToList(rce, "data/sources/coreruleset/powershell.txt")
        SimpleFile.AppendFileToList(rce, "data/sources/coreruleset/rce.txt")

        # entities from payloadidentifier

        SimpleFile.AppendFileToList(lfi_lfd, "data/sources/payloadidentifer/datasets/file-inclusion/ALL_FILES.txt")
        SimpleFile.AppendFileToList(lfi_lfd, "data/sources/payloadidentifer/datasets/path-traversal/ALL_FILES.txt")
        SimpleFile.AppendFileToList(rce, "data/sources/payloadidentifer/datasets/rce/ALL_FILES.txt")
        SimpleFile.AppendFileToList(injection, "data/sources/payloadidentifer/datasets/sql/ALL_FILES.txt")
        SimpleFile.AppendFileToList(xss, "data/sources/payloadidentifer/datasets/xss/ALL_FILES.txt")
        SimpleFile.AppendFileToList(xxe, "data/sources/payloadidentifer/datasets/xxe/ALL_FILES.txt")

        # entities from PayloadAllTheThings

        SimpleFile.AppendDirToList(lfi_lfd, 'data/sources/PayloadsAllTheThings/Directory Traversal/')
        SimpleFile.AppendDirToList(lfi_lfd, 'data/sources/PayloadsAllTheThings/File Inclusion/')
        SimpleFile.AppendDirToList(lfi_lfd, 'data/sources/PayloadsAllTheThings/Insecure Management Interface')
        SimpleFile.AppendDirToList(rce, 'data/sources/PayloadsAllTheThings/Command Injection/')
        SimpleFile.AppendDirToList(injection, 'data/sources/PayloadsAllTheThings/SQL Injection/')
        SimpleFile.AppendDirToList(injection, 'data/sources/PayloadsAllTheThings/LDAP Injection/')
        SimpleFile.AppendDirToList(injection, 'data/sources/PayloadsAllTheThings/NoSQL Injection/')
        SimpleFile.AppendDirToList(crlf, 'data/sources/PayloadsAllTheThings/CRLF Injection/')
        SimpleFile.AppendDirToList(xss, 'data/sources/PayloadsAllTheThings/XSS Injection/')
        SimpleFile.AppendDirToList(xxe, 'data/sources/PayloadsAllTheThings/XXE Injection/')
        SimpleFile.AppendDirToList(open_redirect, 'data/sources/PayloadsAllTheThings/Open Redirect/')

        # # entities from BURP XSS Cheat sheet
        #
        SimpleFile.AppendFileToList(xss, 'data/sources/burp_xss_cheatsheet.txt')

        # # deserialization
        SimpleFile.AppendFileToList(deserialize, 'data/sources/ysoserial_payloads.txt')

        # entities from ML based WAF

        # print(MlJson['type'].unique())
        # MLJsonTypes = ['valid' 'xss' 'sqli' 'path-traversal' 'cmdi']

        MlJson = pd.read_json('data/sources/ml_based_waf.json')

        clean.append(MlJson.where(MlJson['type'] == 'valid').dropna(thresh=1)['pattern'].values.tolist())
        injection.append(MlJson.where(MlJson['type'] == 'sqli').dropna(thresh=1)['pattern'].values.tolist())
        xss.append(MlJson.where(MlJson['type'] == 'xss').dropna(thresh=1)['pattern'].values.tolist())
        rce.append(MlJson.where(MlJson['type'] == 'cmdi').dropna(thresh=1)['pattern'].values.tolist())
        lfi_lfd.append(MlJson.where(MlJson['type'] == 'path-traversal').dropna(thresh=1)['pattern'].values.tolist())

        # entities from ML based WAF CSV

        # print(MlCsv['injection_type'].unique())
        # ['LEGAL' 'XSS' 'SHELL' 'SQL']

        MlCsv = pd.read_csv('data/sources/ml_base_waf_payloads.csv')
        # clean.append(MlCsv.where(MlCsv['injection_type'] == 'LEGAL').dropna(thresh=1)['payload'].values.tolist())
        injection.append(MlCsv.where(MlCsv['injection_type'] == 'SQL').dropna(thresh=1)['payload'].values.tolist())
        rce.append(MlCsv.where(MlCsv['injection_type'] == 'SHELL').dropna(thresh=1)['payload'].values.tolist())
        xss.append(MlCsv.where(MlCsv['injection_type'] == 'XSS').dropna(thresh=1)['payload'].values.tolist())

        # # entities from MSS WAF
        #
        # # print(MSSCvs['injection_type'].unique())
        # # ['LEGAL' 'XSS' 'SHELL' 'SQL']
        #
        MSSCvs = pd.read_csv('data/sources/mss_waf_allpayload.csv')

        # clean.append(MSSCvs.where(MSSCvs['injection_type'] == 'LEGAL').dropna(thresh=1)['payload'].values.tolist())
        injection.append(MSSCvs.where(MSSCvs['injection_type'] == 'SQL').dropna(thresh=1)['payload'].values.tolist())
        rce.append(MSSCvs.where(MSSCvs['injection_type'] == 'SHELL').dropna(thresh=1)['payload'].values.tolist())
        xss.append(MSSCvs.where(MSSCvs['injection_type'] == 'XSS').dropna(thresh=1)['payload'].values.tolist())
        #

        # entities from WAF dataset

        # print(MSSCvs['injection_type'].unique())
        # ['LEGAL' 'XSS' 'SHELL' 'SQL']

        WAFCsv = pd.read_csv('data/sources/waf_dataset.csv')
        # print(WAFCsv['Types'].unique())
        # ['xss' 'sql' 'nosql' 'lfi' 'shell' 'ssti' 'crlf' 'ssi' 'valid']

        clean.append(WAFCsv.where(WAFCsv['Types'] == 'valid').dropna(thresh=1)['Payloads'].values.tolist())
        injection.append(WAFCsv.where(WAFCsv['Types'] == 'nosql').dropna(thresh=1)['Payloads'].values.tolist())
        injection.append(WAFCsv.where(WAFCsv['Types'] == 'sql').dropna(thresh=1)['Payloads'].values.tolist())
        rce.append(WAFCsv.where(WAFCsv['Types'] == 'shell').dropna(thresh=1)['Payloads'].values.tolist())
        rce.append(WAFCsv.where(WAFCsv['Types'] == 'ssi').dropna(thresh=1)['Payloads'].values.tolist())
        xss.append(WAFCsv.where(WAFCsv['Types'] == 'xss').dropna(thresh=1)['Payloads'].values.tolist())
        rce.append(WAFCsv.where(WAFCsv['Types'] == 'ssti').dropna(thresh=1)['Payloads'].values.tolist())
        crlf.append(WAFCsv.where(WAFCsv['Types'] == 'crlf').dropna(thresh=1)['Payloads'].values.tolist())
        lfi_lfd.append(WAFCsv.where(WAFCsv['Types'] == 'lfi').dropna(thresh=1)['Payloads'].values.tolist())

        injection_final_total = list(chain.from_iterable(injection))
        injection_final_unique = set(injection_final_total)

        print("#" * 20 + " Payload Information " + "#" * 20)
        print("Total Injection (SQL/NoSQL) Payloads: " + str(len(injection_final_total)) +
              "\nTotal unique (SQL/NoSQL) payloads: " +
              str(len(injection_final_unique)))

        rce_final_total = list(chain.from_iterable(rce))
        rce_final_unique = set(rce_final_total)

        print("Total RCE Payloads: " + str(len(rce_final_total)) + "\nTotal unique payloads: " +
              str(len(rce_final_unique)))

        final_lfi_lfd_total = list(chain.from_iterable(lfi_lfd))
        final_lfi_lfd_unique = set(final_lfi_lfd_total)

        print("Total LFI/LFD Payloads: " + str(len(final_lfi_lfd_total)) + "\nTotal unique LFI/LFD payloads: " +
              str(len(final_lfi_lfd_unique)))

        final_xss_total = list(chain.from_iterable(xss))
        final_xss_unique = set(final_xss_total)

        print("Total XSS Payloads: " + str(len(final_xss_total)) + "\nTotal unique XSS payloads: " +
              str(len(final_xss_unique)))

        final_crlf_total = list(chain.from_iterable(crlf))
        final_crfl_unique = set(final_crlf_total)

        print("Total CRLF Payloads: " + str(len(final_crlf_total)) + "\nTotal unique CRLF payloads: " +
              str(len(final_crfl_unique)))

        final_xxe_total = list(chain.from_iterable(xxe))
        final_xxe_unique = set(final_xxe_total)

        print("Total XXE Payloads: " + str(len(final_xxe_total)) + "\nTotal unique XXE payloads: " +
              str(len(final_xxe_unique)))

        final_openredirect_total = list(chain.from_iterable(open_redirect))
        final_openredirect_unique = set(final_openredirect_total)

        print("Total OpenRedirect Payloads: " + str(
            len(final_openredirect_total)) + "\nTotal unique OpenRedirect payloads: " +
              str(len(final_openredirect_unique)))

        final_deserialize_total = list(chain.from_iterable(deserialize))
        final_deserialize_unique = set(final_deserialize_total)

        print("Total Deserialize Payloads: " + str(
            len(final_deserialize_total)) + "\nTotal unique Deserialize payloads: " +
              str(len(final_deserialize_unique)))

        final_clean_total = list(chain.from_iterable(clean))
        final_clean_unique = set(final_clean_total)

        print("#" * 20 + " Total Malicious Payloads " + "#" * 20)
        total_malicious = len(final_deserialize_total) + len(final_xss_total) + len(final_xxe_unique) + len(
            injection_final_unique) + \
                          len(final_openredirect_unique) + len(final_crfl_unique) + len(final_openredirect_total) + len(
            rce_final_unique)
        print("Total : " + str(total_malicious))

        print("Total Clean Payloads: " + str(len(final_clean_total)) + "\nTotal unique Clean payloads: " +
              str(len(final_clean_unique)))

        # print("How much more clean data we have")
        # diff = len(final_clean_unique) - total_malicious
        # percent = format(diff / len(final_clean_unique), ".2f")

        # get unique payloads with more 500 samples and fix random state
        sample_needed = int(total_malicious / 2)
        clean_df = pd.DataFrame(final_clean_unique, columns=['Payloads'])
        clean_final_balance = clean_df.sample(n=sample_needed, replace=False, random_state=555).values.tolist()

        print("Selected Clean Samples : " + str(len(clean_final_balance)))

        # let's finally merge and shuffle
        final_list = {"payload": [], "category": []}

        for item in injection_final_unique:
            final_list["payload"].append(item)
            final_list["category"].append("injection")

        for item in rce_final_unique:
            final_list["payload"].append(item)
            final_list["category"].append("rce")

        for item in final_xss_unique:
            final_list["payload"].append(item)
            final_list["category"].append("xss")

        for item in final_xxe_unique:
            final_list["payload"].append(item)
            final_list["category"].append("xxe")

        for item in final_crfl_unique:
            final_list["payload"].append(item)
            final_list["category"].append("crlf")

        for item in final_lfi_lfd_unique:
            final_list["payload"].append(item)
            final_list["category"].append("lfi-ldf")

        for item in final_openredirect_unique:
            final_list["payload"].append(item)
            final_list["category"].append("openredirect")

        for item in final_deserialize_unique:
            final_list["payload"].append(item)
            final_list["category"].append("deserialize")

        for item in clean_final_balance:
            final_list["payload"].append(item)
            final_list["category"].append("clean")

        finale = {"payload": final_list["payload"], "category": final_list["category"]}

        # let's shuffle it and write the final dataset as CSV

        print("#" * 20 + " Shuffling And Creating Final DataSet " + "#" * 20)

        df_finalist = pd.DataFrame(finale, columns=["payload", "category"])
        df_finalist["payload"] = df_finalist["payload"].apply(MergeList)

        # if df_finalist.isnull().sum() > 1:
        #     print("[!] There are null in datas")
        df_shuffled = df_finalist.sample(frac=1, random_state=555).reset_index(drop=True)
        # df_shuffled= df_shuffled.dropna(how="any")
        print(df_shuffled.isnull().sum())
        df_shuffled.to_csv("data/final/final.csv", ",", index=False)

        df_finalist["payload"] = df_finalist['payload'].str.encode('utf-8')
        df_finalist["payload"] = df_finalist["payload"].apply(ToHex)

        # # utf-8 hex encoded version
        # print(bytearray.fromhex(df_finalist['payload'][44]))

        df_shuffled = df_finalist.sample(frac=1, random_state=555).reset_index(drop=True)
        # df_shuffled = df_shuffled.dropna(axis=1)
        df_shuffled.to_csv("data/final/final_hex.csv", ",", index=False)

        print("All done check out data/final folder")


#
#
def ToHex(s):
    return s.hex()


def KeyExist(key, p_dict):
    if key in p_dict.keys():
        return True
    else:
        return False


def CountKeys(key, p_dict):
    count = 0
    for k in p_dict["category"]:
        if k == key:
            count += 1
    return count


def MergeList(s):
    if isinstance(s, list):
        return str(s[0])
    elif isinstance(s, bytes):
        return str(s.decode())
    elif isinstance(s, str):
        return s
    else:
        return s
