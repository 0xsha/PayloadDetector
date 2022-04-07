import glob
import pathlib


class SimpleFile:

    @staticmethod
    def AppendFileToList(target_list, path):
        with open(path, "r") as cl:
            content = cl.read().split('\n')
            target_list.append(content)

    @staticmethod
    def AppendDirToList(target_list, path):
        for file in glob.glob(path + "**", recursive=True):
            if pathlib.Path(file).is_file():
                # with open(file, "rb" , encoding='utf-8' , errors='ignore') as cl:
                with open(file, "r") as cl:
                    content = cl.read().split("\n")
                    target_list.append(content)
