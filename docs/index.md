---
layout: page
title: Home
permalink: "/"
---

Echo just the folder

{{ "assets/" | echo_folder }}

<hr>

List `png`-files (omit parameter, use default type) from `assets` folder (recursive)

{{ "assets/" | list_files }}

<hr>

List `svg`-files from `assets` folder (recursive)

{{ "assets/" | list_files: "*.svg" }}

<hr>

List `subfolders` from `assets` folder (recursive)

{{ "assets/" | list_folders }}

<ul>
    {% assign dir_list = "capi/" | get_folders %}
    {% for dir in dir_list %}
        <li><a href="{{ site.baseurl }}/capi/{{ dir }}">{{ dir }}</a></li>
    {% endfor %}
</ul>
