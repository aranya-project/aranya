---
layout: page
title: Home
permalink: "/"
---

{% comment %}
    Borrowed from https://ongclement.com/blog/github-pages-indexing-directory-copy
{% endcomment %}

{% assign doclist = site.pages | append: ' /capi ' | sort: 'url'  %}
<ul>
    {% for doc in doclist %}
        {% if doc.name contains '.md' or doc.name contains '.html' %}
            <li><a href="{{ site.baseurl }}{{ doc.url }}">{{ doc.url }}</a></li>
        {% endif %}
    {% endfor %}
</ul>
