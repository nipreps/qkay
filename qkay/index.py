from config import IndexTemplate
from pathlib import Path
import os
import glob
import random
import copy


def list_individual_reports(path_reports):
    """
    Returns the list of all html reports in path_reports

    Parameters
    ---------
    path_reports : str
        path of report to modify
    Returns
    -------
    List of reports
    """
    list_of_files = [
        os.path.basename(filename)
        for filename in glob.glob(path_reports + "sub-*.html")
    ]
    return list_of_files


def shuffle_reports(list_of_files, random_seed):
    """
    Shuffle the list of reports

    Parameters
    ---------
    list_of_files: str list
        List of reports
    random_seed: int
        random seed used for the shuffling
    Returns
    -------
    shuffled list
    """
    random.seed(random_seed)
    shuffled_list = copy.deepcopy(list_of_files)
    random.shuffle(shuffled_list)
    return shuffled_list


def anonymize_reports(shuffled_list, dataset_name):
    """
    Anonymizes the list of reports

    Parameters
    ---------
    shuffled_list: str list
        list with original names
    dataset_name: str

    Returns
    -------
    shuffled list
    """
    anonymized_report_list = [
        "A-" + dataset_name + "_" + str(i) for i in range(1, len(shuffled_list) + 1)
    ]
    return anonymized_report_list


if __name__ == "__main__":
    pass
