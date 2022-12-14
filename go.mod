module github.com/wowchemy/starter-hugo-academic

go 1.15

require (
	github.com/wowchemy/wowchemy-hugo-themes/modules/wowchemy-plugin-netlify v1.0.0 // indirect
	github.com/wowchemy/wowchemy-hugo-themes/modules/wowchemy-plugin-netlify-cms v1.0.0 // indirect
	github.com/wowchemy/wowchemy-hugo-themes/modules/wowchemy-plugin-reveal v1.0.0 // indirect
	github.com/wowchemy/wowchemy-hugo-themes/modules/wowchemy/v5 v5.7.1-0.20221127215619-58b270a3e103
)

replace github.com/wowchemy/starter-hugo-academic => ./
replace github.com/wowchemy/wowchemy-hugo-themes/modules/wowchemy-plugin-netlify => /wowchemy-hugo-themes/modules/wowchemy-plugin-netlify
replace github.com/wowchemy/wowchemy-hugo-themes/modules/wowchemy-plugin-netlify-cms => /wowchemy-hugo-themes/modules/wowchemy-plugin-netlify-cms
replace github.com/wowchemy/wowchemy-hugo-themes/modules/wowchemy-plugin-reveal => /wowchemy-hugo-themes/modules/wowchemy-plugin-reveal
replace github.com/wowchemy/wowchemy-hugo-themes/modules/wowchemy/v5 => /wowchemy-hugo-themes/modules/wowchemy