echo auto pack

echo frontend
cd ..\frontend\
yarn build
cd ..\backend\

xcopy /QEY ..\frontend\dist\ .\web\dist\
xcopy /QEY .\web\cyberchef\ .\web\dist\assets\cyberchef\
go-bindata-assetfs -o web/bindata.go -pkg web web/dist/...


echo backend
go build