---
layout: page
title: Home
permalink: "/"
---

{{ "test/" | get_folders }}

<ul>
    {% assign dir_list = "capi/" | get_folders %}
    {% for dir in dir_list %}
        <li><a href="{{ site.baseurl }}/capi/{{ dir }}">{{ dir }}</a></li>
    {% endfor %}
</ul>
