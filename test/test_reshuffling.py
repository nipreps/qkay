# emacs: -*- mode: python; py-indent-offset: 4; indent-tabs-mode: nil -*-
# vi: set ft=python sts=4 ts=4 sw=4 et:
#
# Copyright 2021 The NiPreps Developers <nipreps@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# We support and encourage derived works from this project, please read
# about our expectations at
#
#     https://www.nipreps.org/community/licensing/
#
"""Unit test testing the ramspling functions in index.py."""
from qkay.index import (
    anonymize_reports,
    repeat_reports,
    shuffle_reports,
)


def test_shuffle_reports():
    """
    Test the shuffle_reports function.
    """
    list_of_files = ["file1.txt", "file2.txt", "file3.txt"]
    random_seed = 42

    shuffled_list = shuffle_reports(list_of_files, random_seed)

    assert len(shuffled_list) == len(list_of_files)
    assert set(shuffled_list) == set(list_of_files)


def test_anonymize_reports():
    """
    Test the anonymize_reports function.
    """
    shuffled_list = ["file1.txt", "file2.txt", "file3.txt"]
    dataset_name = "dataset"

    anonymized_list = anonymize_reports(shuffled_list, dataset_name)

    assert len(anonymized_list) == len(shuffled_list)
    assert all(item.startswith("A-" + dataset_name + "_") for item in anonymized_list)


def test_repeat_reports():
    """
    Test the repeat_reports function.
    """
    original_list = ["file1.txt", "file2.txt", "file3.txt"]
    number_of_subjects_to_repeat = 2

    repeated_list = repeat_reports(original_list, number_of_subjects_to_repeat)

    assert len(repeated_list) == len(original_list) + number_of_subjects_to_repeat
    assert all(item in repeated_list for item in original_list)

