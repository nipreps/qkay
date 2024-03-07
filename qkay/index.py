import copy
import glob
import os
import random


def list_individual_reports(path_reports, two_folders=False):
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
    if two_folders:
        list_of_file_condition1 = [
            "/condition1/" + os.path.basename(filename)
            for filename in glob.glob(path_reports + "condition1/" + "sub-*.html")
        ]
        list_of_file_condition2 = [
            "/condition2/" + os.path.basename(filename)
            for filename in glob.glob(path_reports + "condition2/" + "sub-*.html")
        ]

        list_of_files = list_of_file_condition1 + list_of_file_condition2
    else:
        list_of_files = [
            os.path.basename(filename)
            for filename in glob.glob(path_reports + "/**/sub-*.html", recursive=True)
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


def repeat_reports(original_list, number_of_subjects_to_repeat, two_folders=False):
    day = 220830
    time = 543417
    random.seed(day + time)
    if two_folders:

        # Randomly select subjects that will be shown twice, the subjects are the same in the two sets
        list_condition1 = [s for s in original_list if "condition1" in s]
        sourceFile = open("demo.txt", "w")
        print(original_list, list_condition1, file=sourceFile)
        sourceFile.close()
        subset_rep_condition1 = random.sample(
            list_condition1, number_of_subjects_to_repeat
        )
        subset_rep_condition2 = [
            s.replace("condition1", "condition2") for s in subset_rep_condition1
        ]
        subset_rep = subset_rep_condition1 + subset_rep_condition2
    else:
        # Randomly select subjects that will be shown twice
        subset_rep = random.sample(original_list, number_of_subjects_to_repeat)

    original_list.extend(subset_rep)
    return original_list


if __name__ == "__main__":
    pass
