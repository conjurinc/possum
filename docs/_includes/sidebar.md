{% assign section = site.data.sidebar.main[include.section] %}

<ul class="sidebar-nav list-unstyled">
  <li class="section">
    <a href="{{ section.path }}">{{ section.title }}</a>
  <li>

  {% for item in section.items %}
    <li class="item"><a href="{{ item[1].path }}">{{ item[1].title }}</a></li>
  {% endfor %}
</ul>

<ul class="sidebar-nav list-unstyled">
  <li class="item"><a href="https://github.com/cyberark/conjur" target="_blank"><i class="fa fa-github-alt"></i> GitHub</a>
  <li class="item"><a href="https://slackin-conjur.herokuapp.com/" target="_blank"><i class="fa fa-slack"></i> Slack</a>
  <li class="item"><a href="/get-started/install-conjur-cli.html"><i class="fa fa-arrow-down"></i> Download</a>
</ul>
