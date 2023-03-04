import fs from "fs";
class ProductMananger {
  constructor(path) {
    this.path = `./src/dao/filesystem/data/${path}`;
  }
  addProduct = async ({title, description, code, price, stock, thumbnail}) => {
    if(!title || !description || !code || !price || !stock){
      return {success:false,message:`Compruebe que tenga todos los datos solicitados(title, description, code, price, stock, thumbnail(opcional)) para subir correctamente su producto `}
    }
    if (fs.existsSync(this.path)) {
      let info = await fs.promises.readFile(this.path, "utf-8");
      let result = JSON.parse(info);
      const codeCheck = result.find((el) => el.code == code);
      if (codeCheck) return {success:false,message:`El código del producto agregado ya existe, porfavor agrega un producto valido o un nuevo producto`}
      let idParaProducto = result[result.length - 1].id + 1;
      let nuevoProducto = {
        id: idParaProducto,
        title,
        description,
        code,
        price,
        status: true,
        stock,
        thumbnail,
      };
      result.push(nuevoProducto);
      await fs.promises.writeFile(this.path, JSON.stringify(result, null, 2));
      return {success:true,message:"Producto agregado exitosamente:"}
    } else {
      let nuevoProducto = {
        id: 1,
        title,
        description,
        code,
        price,
        status: true,
        stock,
        thumbnail,
      };
      await fs.promises.writeFile(
        this.path,
        JSON.stringify([nuevoProducto], null, 2)
      );
      return {success:true,message:"Producto agregado exitosamente:"}
    }
  };
  getProducts = async () => {
    if (fs.existsSync(this.path)) {
      let info = await fs.promises.readFile(this.path, "utf-8");
      let result = JSON.parse(info);
      return result;
    } else {
      return null;
    }
  };
  getProductById = async (id) => {
    if (fs.existsSync(this.path)) {
      let info = await fs.promises.readFile(this.path, "utf-8");
      let result = JSON.parse(info);
      let mostrarProducto = result.find((product) => product.id==id);
      if (mostrarProducto) {
        return mostrarProducto;
      } else {
        return `Not found, producto no encontrado`;
      }
    } else {
      console.log(`No hay ningún producto en la empresa`);
    }
  };
  uptadeProduct = async (id, propiedadesActualizadas) => {
    if ((id, propiedadesActualizadas)) {
      if (fs.existsSync(this.path)) {
        let info = await fs.promises.readFile(this.path, "utf-8");
        let result = JSON.parse(info);
        let encontrarProducto = result.find((product) => product.id == id);
        if (encontrarProducto) {
          const productUpdates = result.map((product) => {
            if (product.id == id) {
              return { ...product, ...propiedadesActualizadas };
            }
            return product;
          });
          await fs.promises.writeFile(
            this.path,
            JSON.stringify(productUpdates, null, 2)
          );
        } else {
          console.log(`El producto a actualizar no se ha encontrado`);
        }
      } else {
        console.log(`No hay productos para actualizar`);
      }
    } else {
      console.log(`Completa todos los campos para actualizar`);
    }
  };
  deleteProduct=async(id)=>{
    if(fs.existsSync(this.path)){
      let info = await fs.promises.readFile(this.path, "utf-8");
      let result = JSON.parse(info);
      let eliminarProducto=result.filter((prod)=>prod.id!=id)
      result=eliminarProducto
      await fs.promises.writeFile(
        this.path,
        JSON.stringify(result, null, 2)
      );
      return `Producto eliminado correctamente`
    }else{
      `No existe ningún producto dentro de la empresa`
    }
  }
}

const productosEnEmpresa = new ProductMananger("listaDeProductos.json");

export default productosEnEmpresa;
