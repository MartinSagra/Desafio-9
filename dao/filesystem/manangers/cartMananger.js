import fs from "fs";

class CartMananger {
  constructor(path) {
    this.path = `./src/data/${path}`;
  }
  addCart = async () => {
    if (fs.existsSync(this.path)) {
      let info = await fs.promises.readFile(this.path, "utf-8");
      let result = JSON.parse(info);
      let idParaCarrito = result[result.length - 1].id + 1;
      let nuevoCarrito = {
        id: idParaCarrito,
        products: [],
      };
      result.push(nuevoCarrito);
      await fs.promises.writeFile(this.path, JSON.stringify(result, null, 2));
      return `Se ha creado un nuevo carrito, id del carrito=${idParaCarrito}`;
    } else {
      let nuevoCarrito = {
        id: 1,
        products: [],
      };
      await fs.promises.writeFile(
        this.path,
        JSON.stringify([nuevoCarrito], null, 2)
      );
      return `Se ha creado un nuevo carrito, id del carrito=1`;
    }
  };
  getCart = async (id) => {
    if (fs.existsSync(this.path)) {
      let info = await fs.promises.readFile(this.path, "utf-8");
      let result = JSON.parse(info);
      let mostrarProducto = result.find((carrito) => carrito.id == id);
      if (mostrarProducto) {
        return mostrarProducto;
      } else {
        return `Not found, carrito no encontrado, verifique el id ingresado`;
      }
    } else {
      return `No hay ningún carrito con ese id`;
    }
  };
  addProductInCart = async (id, product) => {
    let info = await fs.promises.readFile(this.path, "utf-8");
    let result = JSON.parse(info);
    let agregarProducto = result.map((prod) => {
      if (prod.id == id) {
        if (prod.products.length > 0) {
          let repiteProducto = prod.products.filter(
            (prod) => prod.product == product
          );
          if (repiteProducto.length > 0) {
            let cambiarCantidad = repiteProducto.map((objeto) => {
              return { ...objeto, quantity: objeto.quantity + 1 };
            });
            let nuevoProdProducts = prod.products.map((producto) => {
              if (producto.product == product) {
                producto=cambiarCantidad[0]
                return producto
              }
              return producto;
            });
            prod.products=nuevoProdProducts
            return prod
          } else {
            let nuevoProducto = {
              product: Number(product),
              quantity: 1,
            };
            prod.products.push(nuevoProducto);
          }
        } else {
          let nuevoProducto = {
            product: Number(product),
            quantity: 1,
          };
          prod.products.push(nuevoProducto);
        }
      }
      return prod;
    });
    await fs.promises.writeFile(
      this.path,
      JSON.stringify(agregarProducto, null, 2)
    );
    
  };
}
const carrito = new CartMananger("carrito.json");
export default carrito;
