import copy
import glob
import os
import random


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


def repeat_reports(original_list, number_of_subjects_to_repeat):
    """
    Repeat a subset of reports in a deep copy of the original list.

    Parameters:
    original_list (list): The original list of reports.
    number_of_subjects_to_repeat (int): The number of subjects to repeat.

    Returns:
    list: A new list with the specified subset repeated, leaving the original list intact.

    Note:
    This function creates a deep copy of the original list and then randomly selects a subset of reports
    from the copied list. The selected subset is appended to the end of the copied list, effectively repeating them.
    The random seed for selection is based on the given day and time.
    """
    day = 220830
    time = 543417
    random.seed(day + time)
    copied_list = copy.deepcopy(original_list)
    subset_rep = random.sample(copied_list, number_of_subjects_to_repeat)
    copied_list.extend(subset_rep)

    return copied_list


if __name__ == "__main__":
    pass
