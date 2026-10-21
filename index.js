var htmlparser = require('htmlparser2');
var _ = require('lodash');
var he = require('he');

module.exports = sanitizeHtml;

// Ignore the _recursing flag; it's there for recursive
// invocation as a guard against this exploit:
// https://github.com/fb55/htmlparser2/issues/105

function sanitizeHtml(html, options, _recursing) {
  var result = '';

  function Frame(tag, attribs) {
    var that = this;
    this.tag = tag;
    this.attribs = attribs || {};
    this.tagPosition = result.length;
    this.text = ''; // Node inner text

    this.updateParentNodeText = function() {
      if (stack.length) {
          var parentFrame = stack[stack.length - 1];
          parentFrame.text += that.text;
      }
    };
  }

  if (!options) {
    options = sanitizeHtml.defaults;
  } else {
    _.defaults(options, sanitizeHtml.defaults);
  }
  // Tags that contain something other than HTML. If we are not allowing
  // these tags, we should drop their content too. For other tags you would
  // drop the tag but keep its content.
  var nonTextTagsMap = {
    script: true,
    style: true
  };
  var allowedTagsMap;
  if(options.allowedTags) {
    allowedTagsMap = {};
    _.each(options.allowedTags, function(tag) {
      allowedTagsMap[tag] = true;
    });
  }
  var selfClosingMap = {};
  _.each(options.selfClosing, function(tag) {
    selfClosingMap[tag] = true;
  });
  var allowedAttributesMap;
  if(options.allowedAttributes) {
    allowedAttributesMap = {};
    _.each(options.allowedAttributes, function(attributes, tag) {
      allowedAttributesMap[tag] = {};
      _.each(attributes, function(name) {
        allowedAttributesMap[tag][name] = true;
      });
    });
  }
  var allowedClassesMap = {};
  _.each(options.allowedClasses, function(classes, tag) {
    // Implicitly allows the class attribute
    if(allowedAttributesMap) {
      if (!allowedAttributesMap[tag]) {
        allowedAttributesMap[tag] = {};
      }
      allowedAttributesMap[tag]['class'] = true;
    }

    allowedClassesMap[tag] = {};
    _.each(classes, function(name) {
      allowedClassesMap[tag][name] = true;
    });
  });

  var transformTagsMap = {};
  _.each(options.transformTags, function(transform, tag){
    if (typeof transform === 'function') {
      transformTagsMap[tag] = transform;
    } else if (typeof transform === "string") {
      transformTagsMap[tag] = sanitizeHtml.simpleTransform(transform);
    }
  });

  var depth = 0;
  var stack = [];
  var skipMap = {};
  var transformMap = {};
  var skipText = false;
  var parser = new htmlparser.Parser({
    onopentag: function(name, attribs) {
      var frame = new Frame(name, attribs);
      stack.push(frame);

      var skip = false;
      if (_.has(transformTagsMap, name)) {
        var transformedTag = transformTagsMap[name](name, attribs);

        frame.attribs = attribs = transformedTag.attribs;
        if (name !== transformedTag.tagName) {
          frame.name = name = transformedTag.tagName;
          transformMap[depth] = transformedTag.tagName;
        }
      }

      if (allowedTagsMap && !_.has(allowedTagsMap, name)) {
        skip = true;
        if (_.has(nonTextTagsMap, name)) {
          skipText = true;
        }
        skipMap[depth] = true;
      }
      depth++;
      if (skip) {
        // We want the contents but not this tag
        return;
      }
      result += '<' + name;
      if (!allowedAttributesMap || _.has(allowedAttributesMap, name)) {
        _.each(attribs, function(value, a) {
          if (!allowedAttributesMap || _.has(allowedAttributesMap[name], a)) {
            if ((a === 'href') || (a === 'src')) {
              if (naughtyHref(value)) {
                delete frame.attribs[a];
                return;
              }
            }
            // `<meta http-equiv="refresh" content="0;url=...">` navigates to a
            // URL embedded in `content`, so scheme check that URL too
            // (GHSA-cv27-6wvh-8x7j). Other meta `content` values are left alone.
            if (name === 'meta' && a.toLowerCase() === 'content' && isRefresh(attribs) && naughtyRefresh(value)) {
              delete frame.attribs[a];
              return;
            }
            if (a === 'class') {
              value = filterClasses(value, allowedClassesMap[name]);
              if (!value.length) {
                delete frame.attribs[a];
                return;
              }
            }
            result += ' ' + a;
            if (value.length) {
              // Values are ALREADY escaped, calling escapeHtml here
              // results in double escapes.
              // However, a bug in the HTML parser allows you to use malformed 
              // markup to slip unescaped quotes through, so we strip them explicitly.
              // @see https://github.com/punkave/sanitize-html/issues/19
              result += '="' + value.replace(/"/g, '&quot;') + '"';
            }
          } else {
            delete frame.attribs[a];
          }
        });
      }
      if (_.has(selfClosingMap, name)) {
        result += " />";
      } else {
        result += ">";
      }
    },
    ontext: function(text) {
      if (skipText) {
        return;
      }
      // It is NOT actually raw text, entities are already escaped.
      // If we call escapeHtml here we wind up double-escaping.
      result += text;
      if (stack.length) {
           var frame = stack[stack.length - 1];
           frame.text += text;
      }
    },
    onclosetag: function(name) {
      var frame = stack.pop();
      if (!frame) {
        // Do not crash on bad markup
        return;
      }
      skipText = false;
      depth--;
      if (skipMap[depth]) {
        delete skipMap[depth];
        frame.updateParentNodeText();
        return;
      }

      if (transformMap[depth]) {
        name = transformMap[depth];
        delete transformMap[depth];
      }

      if (options.exclusiveFilter && options.exclusiveFilter(frame)) {
         result = result.substr(0, frame.tagPosition);
         return;
      }

      frame.updateParentNodeText();

      if (_.has(selfClosingMap, name)) {
         // Already output />
         return;
      }

      result += "</" + name + ">";
    }
  });
  parser.write(html);
  parser.end();

  // Invoke recursively until we stop finding
  // clever little nesting exploits
  if (!_recursing) {
    while (true) {
      var newResult = sanitizeHtml(result, options, true);
      if (newResult === result) {
        return result;
      }
      result = newResult;
    }
  }
  return result;

  function escapeHtml(s) {
    if (s === 'undefined') {
      s = '';
    }
    if (typeof(s) !== 'string') {
      s = s + '';
    }
    return s.replace(/\&/g, '&amp;').replace(/</g, '&lt;').replace(/\>/g, '&gt;').replace(/\"/g, '&quot;');
  }

  function naughtyHref(href) {
    // So we don't get faked out by a hex or decimal escaped javascript URL #1
    href = he.decode(href);
    // Browsers ignore character codes of 32 (space) and below in a surprising
    // number of situations. Start reading here:
    // https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet#Embedded_tab
    href = href.replace(/[\x00-\x20]+/g, '');
    // Clobber any comments in URLs, which the browser might
    // interpret inside an XML data island, allowing
    // a javascript: URL to be snuck through
    while (true) {
      var firstIndex = href.indexOf('<!--');
      if (firstIndex === -1) {
        break;
      }
      var lastIndex = href.indexOf('-->', firstIndex + 4);
      if (lastIndex === -1) {
        break;
      }
      href = href.substring(0, firstIndex) + href.substring(lastIndex + 3);
    }
    // Case insensitive so we don't get faked out by JAVASCRIPT #1
    var matches = href.match(/^([a-zA-Z]+)\:/);
    if (!matches) {
      // No scheme = no way to inject js (right?)
      return false;
    }
    var scheme = matches[1].toLowerCase();
    return (!_.contains(options.allowedSchemes, scheme));
  }

  function isRefresh(attribs) {
    return _.some(_.keys(attribs), function(a) {
      return a.toLowerCase() === 'http-equiv' &&
        String(attribs[a]).trim().toLowerCase() === 'refresh';
    });
  }

  // True if the `content` of a `<meta http-equiv="refresh">` must be dropped:
  // its destination URL fails the scheme policy, or it cannot be parsed as a
  // refresh at all (a browser would ignore it then, so nothing is lost).
  // Extracts the URL the way the HTML standard's "shared declarative refresh
  // steps" do, so that spelling, separator, quoting and case variations of
  // `url=`, or no `url=` at all, all yield the URL a browser would navigate to.
  function naughtyRefresh(content) {
    // Attribute values are still entity-encoded here, so decode them the way
    // the browser will before reading the URL out of them
    var input = he.decode(String(content));
    var isWhitespace = function(c) {
      return c === ' ' || c === '\t' || c === '\n' || c === '\f' || c === '\r';
    };
    var position = 0;
    var skipWhitespace = function() {
      while (position < input.length && isWhitespace(input.charAt(position))) {
        position++;
      }
    };
    var lowerAt = function(i) {
      return input.charAt(i).toLowerCase();
    };
    skipWhitespace();
    var timeStart = position;
    while (position < input.length && /[0-9.]/.test(input.charAt(position))) {
      position++;
    }
    if (position === timeStart) {
      return true;
    }
    if (position < input.length) {
      var c = input.charAt(position);
      if (c !== ';' && c !== ',' && !isWhitespace(c)) {
        return true;
      }
      skipWhitespace();
      if (input.charAt(position) === ';' || input.charAt(position) === ',') {
        position++;
      }
      skipWhitespace();
    }
    if (position >= input.length) {
      // No URL: refreshes the current document
      return false;
    }
    var url = input.slice(position);
    var quoted = true;
    if (lowerAt(position) === 'u') {
      quoted = false;
      if (lowerAt(position + 1) === 'r' && lowerAt(position + 2) === 'l') {
        position += 3;
        skipWhitespace();
        if (input.charAt(position) === '=') {
          position++;
          skipWhitespace();
          quoted = true;
        }
      }
    }
    if (quoted) {
      var quote = input.charAt(position);
      if (quote === '"' || quote === '\'') {
        position++;
      }
      url = input.slice(position);
      if (quote === '"' || quote === '\'') {
        var end = url.indexOf(quote);
        if (end !== -1) {
          url = url.slice(0, end);
        }
      }
    }
    return naughtyHref(url);
  }

  function filterClasses(classes, allowed) {
    if (!allowed) {
      // The class attribute is allowed without filtering on this tag
      return classes;
    }
    classes = classes.split(/\s+/);
    return _.filter(classes, function(c) {
      return _.has(allowed, c);
    }).join(' ');
  }
}

// Defaults are accessible to you so that you can use them as a starting point
// programmatically if you wish

sanitizeHtml.defaults = {
  allowedTags: [ 'h3', 'h4', 'h5', 'h6', 'blockquote', 'p', 'a', 'ul', 'ol', 'nl', 'li', 'b', 'i', 'strong', 'em', 'strike', 'code', 'hr', 'br', 'div', 'table', 'thead', 'caption', 'tbody', 'tr', 'th', 'td', 'pre' ],
  allowedAttributes: {
    a: [ 'href', 'name', 'target' ],
    // We don't currently allow img itself by default, but this
    // would make sense if we did
    img: [ 'src' ]
  },
  // Lots of these won't come up by default because we don't allow them
  selfClosing: [ 'img', 'br', 'hr', 'area', 'base', 'basefont', 'input', 'link', 'meta' ],
  // URL schemes we permit
  allowedSchemes: [ 'http', 'https', 'ftp', 'mailto' ]
};

sanitizeHtml.simpleTransform = function(newTagName, newAttribs, merge) {
  merge = (merge === undefined) ? true : merge;
  newAttribs = newAttribs || {};

  return function(tagName, attribs) {
    var attrib;
    if (merge) {
      for (attrib in newAttribs) {
        attribs[attrib] = newAttribs[attrib];
      }
    } else {
      attribs = newAttribs;
    }

    return {
      tagName: newTagName,
      attribs: attribs
    };
  };
};
