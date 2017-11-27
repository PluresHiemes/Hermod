"General
set colorcolumn=81
scriptencoding utf-8
set bs=indent,eol,start "allows backspace over everything in insert
set ignorecase
set mouse=a
set ruler
set wildmenu
set wildmode=longest,list,full
set wildignore+=*.so,*.class
let g:matchparen_insert_timeout=5
set number

"Tab shit
set autoindent
set tabstop=4
set clipboard=unnamed
set smartindent

"color shit
colorscheme PaperColor
set t_Co=256
set background=light

"fuck you python
"if $LANG =~ '\(UTF\|utf\)-\?8' || $LC_CTYPE =~ '\(UTF\utf\)-\?8'
		"set list listchars=tab:
highlight ExtraWhitespace ctermbg=darkgreen guibg=lightgreen
